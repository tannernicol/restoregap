// Package intent defines the normalized ChangeIntent domain type and the
// parsers that produce it: action-intent YAML and unified diffs. It has no
// dependencies beyond the standard library and is imported by internal/rules
// and internal/engine as a plain data type — it performs no evaluation.
package intent

import (
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// Action is a declared action-intent verb. Kept as a plain string (not a
// closed enum) because callers may pass through arbitrary actions for
// display even when no rule recognizes them; guards match by exact string.
type Action string

// Known actions accepted by the local action-intent YAML schema (v2 keeps
// the Python vocabulary: docs/ARCHITECTURE.md, adapters/local/models.py).
const (
	ActionDeleteFile    Action = "delete_file"
	ActionModifyFile    Action = "modify_file"
	ActionMoveFile      Action = "move_file"
	ActionRunCommand    Action = "run_command"
	ActionPackageUpdate Action = "package_update"
	ActionSystemUpdate  Action = "system_update"
	ActionInstallPkg    Action = "install_package"
	ActionRemovePkg     Action = "remove_package"
)

var validActions = map[Action]bool{
	ActionDeleteFile:    true,
	ActionModifyFile:    true,
	ActionMoveFile:      true,
	ActionRunCommand:    true,
	ActionPackageUpdate: true,
	ActionSystemUpdate:  true,
	ActionInstallPkg:    true,
	ActionRemovePkg:     true,
}

// ChangeIntent is the normalized, engine-facing description of one proposed
// change, whether it came from an action-intent YAML file or a diff hunk.
type ChangeIntent struct {
	Action        Action
	Command       string
	Packages      []string
	Paths         []string
	TargetPaths   []string
	Actor         string
	ContextWindow string
	Description   string
	// Source identifies where this intent came from for evidence rendering:
	// "action-intent" or "diff".
	Source string
}

// AllPaths returns the union of declared and target paths, the set guard
// path matching should consider.
func (c ChangeIntent) AllPaths() []string {
	if len(c.TargetPaths) == 0 {
		return c.Paths
	}
	out := make([]string, 0, len(c.Paths)+len(c.TargetPaths))
	out = append(out, c.Paths...)
	out = append(out, c.TargetPaths...)
	return out
}

// rawIntent is the YAML wire shape of an action-intent file (v2 keeps the
// Python field set: action, command, packages, paths/path, target_paths/
// target_path, actor, context_window, description).
type rawIntent struct {
	Version       int      `yaml:"version"`
	Action        string   `yaml:"action"`
	Path          string   `yaml:"path"`
	Paths         []string `yaml:"paths"`
	TargetPath    string   `yaml:"target_path"`
	TargetPaths   []string `yaml:"target_paths"`
	Packages      []string `yaml:"packages"`
	Command       string   `yaml:"command"`
	Actor         string   `yaml:"actor"`
	ContextWindow string   `yaml:"context_window"`
	Description   string   `yaml:"description"`
}

// Parse decodes an action-intent YAML document into a ChangeIntent.
func Parse(r io.Reader) (ChangeIntent, error) {
	var raw rawIntent
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return ChangeIntent{}, fmt.Errorf("intent: invalid YAML: %w", err)
	}
	if raw.Version != 1 && raw.Version != 2 {
		return ChangeIntent{}, fmt.Errorf("intent: version must be 1 or 2, got %d", raw.Version)
	}
	if raw.Action == "" {
		return ChangeIntent{}, fmt.Errorf("intent: action is required")
	}
	action := Action(raw.Action)
	if !validActions[action] {
		return ChangeIntent{}, fmt.Errorf("intent: unknown action %q", raw.Action)
	}

	paths := raw.Paths
	if raw.Path != "" {
		paths = append([]string{raw.Path}, paths...)
	}
	targetPaths := raw.TargetPaths
	if raw.TargetPath != "" {
		targetPaths = append([]string{raw.TargetPath}, targetPaths...)
	}

	switch action {
	case ActionDeleteFile, ActionModifyFile, ActionMoveFile:
		if len(paths) == 0 {
			return ChangeIntent{}, fmt.Errorf("intent: action %q requires path or paths", raw.Action)
		}
	case ActionPackageUpdate, ActionInstallPkg, ActionRemovePkg:
		if len(raw.Packages) == 0 {
			return ChangeIntent{}, fmt.Errorf("intent: action %q requires packages", raw.Action)
		}
	case ActionRunCommand:
		if raw.Command == "" {
			return ChangeIntent{}, fmt.Errorf("intent: action %q requires command", raw.Action)
		}
	}

	return ChangeIntent{
		Action:        action,
		Command:       raw.Command,
		Packages:      raw.Packages,
		Paths:         paths,
		TargetPaths:   targetPaths,
		Actor:         raw.Actor,
		ContextWindow: raw.ContextWindow,
		Description:   raw.Description,
		Source:        "action-intent",
	}, nil
}
