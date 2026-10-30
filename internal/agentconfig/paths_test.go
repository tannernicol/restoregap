// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package agentconfig

import (
	"path/filepath"
	"testing"
)

func TestPaths(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	for _, tc := range []struct{ vendor, scope, settings, registry string }{
		{"claude", "user", filepath.Join(home, ".claude", "settings.json"), filepath.Join(home, ".claude.json")},
		{"claude", "project", filepath.Join(project, ".claude", "settings.json"), filepath.Join(project, ".mcp.json")},
		{"gemini", "user", filepath.Join(home, ".gemini", "settings.json"), filepath.Join(home, ".gemini", "settings.json")},
		{"gemini", "project", filepath.Join(project, ".gemini", "settings.json"), filepath.Join(project, ".gemini", "settings.json")},
		{"cursor", "user", filepath.Join(home, ".cursor", "hooks.json"), filepath.Join(home, ".cursor", "mcp.json")},
		{"cursor", "project", filepath.Join(project, ".cursor", "hooks.json"), filepath.Join(project, ".cursor", "mcp.json")},
	} {
		t.Run(tc.vendor+"/"+tc.scope, func(t *testing.T) {
			settings, registry := Paths(tc.vendor, home, project, tc.scope)
			if settings != tc.settings || registry != tc.registry {
				t.Fatalf("Paths = (%q, %q), want (%q, %q)", settings, registry, tc.settings, tc.registry)
			}
		})
	}
}
