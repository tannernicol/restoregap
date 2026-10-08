// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package bundle

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

// Loaded is a verified bundle's decoded contents: its manifest, its embedded
// context files merged into one Context, and the signature block the archive
// carried — so a service can pin the signer's public key and display the
// signature to a reviewer without re-opening the archive.
type Loaded struct {
	Manifest  Manifest
	Context   contextspec.Context
	Signature Signature
}

// LoadVerified verifies path (Verify) and, only if it checks out, decodes
// and merges its embedded context files into one contextspec.Context —
// the trusted input `bundle merge` / `status --fleet` build fleet rows
// from. It refuses (rather than returning partial data) when verification
// fails: fleet aggregation must never silently ingest an unverified or
// tampered bundle alongside good ones.
func LoadVerified(path string) (Manifest, contextspec.Context, error) {
	archive, err := os.ReadFile(path) //nolint:gosec // caller-provided bundle path, same trust level as any other CLI arg
	if err != nil {
		// Same two-layer text the path-based Verify-then-Load flow always had.
		return Manifest{}, contextspec.Context{}, fmt.Errorf("%s%w", scoped("bundle", path),
			fmt.Errorf("%s%w", scoped("bundle verify", path), err))
	}
	loaded, err := loadVerified(archive, path)
	if err != nil {
		return Manifest{}, contextspec.Context{}, err
	}
	return loaded.Manifest, loaded.Context, nil
}

// LoadVerifiedBytes is LoadVerified over an in-memory archive. It verifies
// first and refuses on any failure, exactly like LoadVerified, and also
// returns the manifest.sig block the archive carried.
func LoadVerifiedBytes(archive []byte) (Loaded, error) {
	return loadVerified(archive, "")
}

// loadVerified is the single load implementation. label is the path to name
// in error text ("" for in-memory callers).
//
// contextspec only loads from paths (LoadAll applies per-file scope defaults
// and strict id-uniqueness across files; Parse handles just one document and
// stamps no scope/Origin), so the embedded context files are still staged in
// a temp dir here rather than re-implementing that merge. The temp dir is
// private to this call (0600 files, removed on return).
func loadVerified(archive []byte, label string) (Loaded, error) {
	lead := scoped("bundle", label)
	members, result, err := verifyArchive(archive, "", label)
	if err != nil {
		return Loaded{}, fmt.Errorf("%s%w", lead, err)
	}
	if !result.OK {
		return Loaded{}, fmt.Errorf("%sfailed verification: %s", lead, result.Reason)
	}

	// verifyArchive already proved manifest.sig exists and parses.
	var sig Signature
	if err := json.Unmarshal(members[signatureName], &sig); err != nil {
		return Loaded{}, fmt.Errorf("%sunreadable %s: %w", lead, signatureName, err)
	}
	loaded := Loaded{Manifest: result.Manifest, Signature: sig}
	if len(result.Manifest.ContextFiles) == 0 {
		return loaded, nil
	}

	tmp, err := os.MkdirTemp("", "restoregap-bundle-ctx-")
	if err != nil {
		return Loaded{}, fmt.Errorf("%s%w", lead, err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	paths := make([]string, 0, len(result.Manifest.ContextFiles))
	for _, ref := range result.Manifest.ContextFiles {
		dst := filepath.Join(tmp, filepath.Base(ref.Name))
		if err := os.WriteFile(dst, members[ref.Name], 0o600); err != nil {
			return Loaded{}, fmt.Errorf("%s%w", lead, err)
		}
		paths = append(paths, dst)
	}
	ctx, err := contextspec.LoadAll(paths)
	if err != nil {
		return Loaded{}, fmt.Errorf("%smerging embedded context files: %w", lead, err)
	}
	loaded.Context = ctx
	return loaded, nil
}
