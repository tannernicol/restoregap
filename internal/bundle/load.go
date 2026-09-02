// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package bundle

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

// LoadVerified verifies path (Verify) and, only if it checks out, decodes
// and merges its embedded context files into one contextspec.Context —
// the trusted input `bundle merge` / `status --fleet` build fleet rows
// from. It refuses (rather than returning partial data) when verification
// fails: fleet aggregation must never silently ingest an unverified or
// tampered bundle alongside good ones.
func LoadVerified(path string) (Manifest, contextspec.Context, error) {
	result, err := Verify(path)
	if err != nil {
		return Manifest{}, contextspec.Context{}, fmt.Errorf("bundle: %s: %w", path, err)
	}
	if !result.OK {
		return Manifest{}, contextspec.Context{}, fmt.Errorf("bundle: %s: failed verification: %s", path, result.Reason)
	}
	if len(result.Manifest.ContextFiles) == 0 {
		return result.Manifest, contextspec.Context{}, nil
	}

	members, err := readTarGz(path)
	if err != nil {
		return Manifest{}, contextspec.Context{}, fmt.Errorf("bundle: %s: %w", path, err)
	}
	tmp, err := os.MkdirTemp("", "restoregap-bundle-ctx-")
	if err != nil {
		return Manifest{}, contextspec.Context{}, fmt.Errorf("bundle: %s: %w", path, err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	paths := make([]string, 0, len(result.Manifest.ContextFiles))
	for _, ref := range result.Manifest.ContextFiles {
		dst := filepath.Join(tmp, filepath.Base(ref.Name))
		if err := os.WriteFile(dst, members[ref.Name], 0o600); err != nil {
			return Manifest{}, contextspec.Context{}, fmt.Errorf("bundle: %s: %w", path, err)
		}
		paths = append(paths, dst)
	}
	ctx, err := contextspec.LoadAll(paths)
	if err != nil {
		return Manifest{}, contextspec.Context{}, fmt.Errorf("bundle: %s: merging embedded context files: %w", path, err)
	}
	return result.Manifest, ctx, nil
}
