// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package bundle

import (
	"encoding/json"
	"fmt"
)

// Inspect reads a bundle's manifest.json WITHOUT checking the signature or
// any content digest — `bundle inspect` is "what does this bundle claim",
// `bundle verify` is "do I believe it". Use Verify first for anything that
// matters; Inspect is for a human looking at a bundle they already trust
// (or are about to feed to Verify anyway).
func Inspect(path string) (Manifest, error) {
	members, err := readTarGz(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("bundle inspect: %s: %w", path, err)
	}
	raw, ok := members[manifestName]
	if !ok {
		return Manifest{}, fmt.Errorf("bundle inspect: %s: missing %s", path, manifestName)
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("bundle inspect: %s: unreadable %s: %w", path, manifestName, err)
	}
	return manifest, nil
}
