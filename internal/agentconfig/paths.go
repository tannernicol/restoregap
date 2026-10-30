// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package agentconfig shares agent configuration locations between installation
// and read-only coverage discovery.
package agentconfig

import "path/filepath"

// Paths returns the hook settings and the registry the agent actually reads.
func Paths(vendor, home, project, scope string) (settings, registry string) {
	base := home
	if scope == "project" {
		base = project
	}
	settings = filepath.Join(base, "."+vendor, "settings.json")
	registry = settings
	switch vendor {
	case "claude":
		registry = filepath.Join(home, ".claude.json")
		if scope == "project" {
			registry = filepath.Join(project, ".mcp.json")
		}
	case "cursor":
		settings = filepath.Join(base, ".cursor", "hooks.json")
		registry = filepath.Join(base, ".cursor", "mcp.json")
	}
	return settings, registry
}
